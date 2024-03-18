import argparse
import datetime
import enum
import difflib
import hashlib
import json
import operator
import os
import stat
import struct
import sys
import time
import zlib
import urllib
import utils
import collections

class Gitd:
        
    # ----------------------------------------------------------------
    # Define Part
    # ----------------------------------------------------------------

    '''
    ctime: created time
    mtime: modified time
    dev: device information
    ino: 
    mode: access limited mode
    sha1: SHA1 of the file
    flags: 
    path: path to the file
    '''
    

    class ObjectType(enum.Enum):
        commit = 1
        tree = 2
        blob = 3

    # ----------------------------------------------------------------
    # Init Part
    # ----------------------------------------------------------------
        
    def __init__(self, repo_path):
        self.repo_path = repo_path
        self.IndexEntry = collections.namedtuple('IndexEntry', [
        'ctime_s', 'ctime_n', 'mtime_s', 'mtime_n', 'dev', 'ino', 'mode',
        'uid', 'gid', 'size', 'sha1', 'flags', 'path',
    ])
        

    # Path to the local database (JSON file)
    db_path = 'pygit_db.json'

    def _load_db(self):
        """Load the repository database from a JSON file."""
        try:
            with open(self.db_path, 'r') as db_file:
                db = json.load(db_file)
        except (FileNotFoundError, json.JSONDecodeError):
            db = {}
        return db

    def _save_db(self, db):
        """Save the repository database to a JSON file."""
        with open(self.db_path, 'w') as db_file:
            json.dump(db, db_file, indent=4)

    def _record_repo_init(self):
        """Record the repository initialization in the database."""
        db = self._load_db()
        db[self.repo_path] = {
            'init_time': datetime.datetime.now().isoformat(),
            'operations': []
        }
        self._save_db(db)

    def _record_repo_operation(self, operation):
        """Record a repository operation with its timestamp in the database."""
        db = self._load_db()
        if self.repo_path not in db:
            self._record_repo_init()  # Initialize repo in the database if not present
            db = self._load_db()
        db[self.repo_path]['operations'].append({
            'operation': operation,
            'time': datetime.datetime.now().isoformat()
        })
        self._save_db(db)

    def init(self):
        os.mkdir(self.repo_path)
        os.mkdir(os.path.join(self.repo_path,'.git'))
        for name in ['objects','refs','refs/heads']:
            os.mkdir(os.path.join(self.repo_path,'.git',name))
        utils.write_file(os.path.join(self.repo_path,'.git','HEAD'),b'ref:refs/heads/master')
        self._record_repo_init() 
        print('Initialized Empty Repository: {}'.format(self.repo_path))


    # ----------------------------------------------------------------
    # Hash Part
    # ----------------------------------------------------------------

    def hash_object(self, data, obj_type, write=True):
        header = '{} {}'.format(obj_type, len(data)).encode()
        full_data = header + b'\x00' + data
        sha1 = hashlib.sha1(full_data).hexdigest()
        if write:
            path = os.path.join(self.repo_path,'.git', 'objects', sha1[:2], sha1[2:])
            if not os.path.exists(path):
                os.makedirs(os.path.dirname(path), exist_ok=True)
                utils.write_file(path, zlib.compress(full_data))
        return sha1

    def find_object(self, sha1_prefix):
        """
        Find object with given SHA-1 prefix and return path to object in object
        store, or raise ValueError if there are no objects or multiple objects
        with this prefix.
        """
        if len(sha1_prefix) < 2:
            raise ValueError('hash prefix must be 2 or more characters')
        obj_dir = os.path.join(self.repo_path,'.git', 'objects', sha1_prefix[:2])
        rest = sha1_prefix[2:]
        objects = [name for name in os.listdir(obj_dir) if name.startswith(rest)]
        if not objects:
            raise ValueError('object {!r} not found'.format(sha1_prefix))
        if len(objects) >= 2:
            raise ValueError('multiple objects ({}) with prefix {!r}'.format(
                    len(objects), sha1_prefix))
        return os.path.join(obj_dir, objects[0])


    def read_object(self, sha1_prefix):
        path = self.find_object(sha1_prefix)
        full_data = zlib.decompress(utils.read_file(path))
        nul_index = full_data.index(b'\x00')
        header = full_data[:nul_index]
        obj_type, size_str = header.decode().split()
        size = int(size_str)
        data = full_data[nul_index + 1:]
        assert size == len(data), 'expected size {}, got {} bytes'.format(
                size, len(data))
        return (obj_type, data)

    # API - allow user to read type and content of file
    def cat_file(self, mode, sha1_prefix):
        """
        Write the contents of (or info about) object with given SHA-1 prefix to
        stdout. If mode is 'commit', 'tree', or 'blob', print raw data bytes of
        object. If mode is 'size', print the size of the object. If mode is
        'type', print the type of the object. If mode is 'pretty', print a
        prettified version of the object.
        """
        obj_type, data = self.read_object(sha1_prefix)
        if mode in ['commit', 'tree', 'blob']:
            if obj_type != mode:
                raise ValueError('expected object type {}, got {}'.format(
                        mode, obj_type))
            sys.stdout.buffer.write(data)
        elif mode == 'size':
            print(len(data))
        elif mode == 'type':
            print(obj_type)
        elif mode == 'pretty':
            if obj_type in ['commit', 'blob']:
                sys.stdout.buffer.write(data)
            elif obj_type == 'tree':
                for mode, path, sha1 in self.read_tree(data=data):
                    type_str = 'tree' if stat.S_ISDIR(mode) else 'blob'
                    print('{:06o} {} {}\t{}'.format(mode, type_str, sha1, path))
            else:
                assert False, 'unhandled object type {!r}'.format(obj_type)
        else:
            raise ValueError('unexpected mode {!r}'.format(mode))

    # ----------------------------------------------------------------
    # Index Part
    # ----------------------------------------------------------------

    def read_index(self):
        """Read git index file and return list of IndexEntry objects."""
        # Read git index file
        try:
            data = utils.read_file(os.path.join(self.repo_path,'.git', 'index'))
        except FileNotFoundError:
            return []

        # Verify SHA-1 digest of file to ensure intergity
        digest = hashlib.sha1(data[:-20]).digest()
        assert digest == data[-20:], 'invalid index checksum'
        signature, version, num_entries = struct.unpack('!4sLL', data[:12])
        assert signature == b'DIRC', \
                'invalid index signature {}'.format(signature)
        assert version == 2, 'unknown index version {}'.format(version)
        entry_data = data[12:-20]
        entries = []
        i = 0
        while i + 62 < len(entry_data):
            fields_end = i + 62
            fields = struct.unpack('!LLLLLLLLLL20sH',
                                entry_data[i:fields_end])
            path_end = entry_data.index(b'\x00', fields_end)
            path = entry_data[fields_end:path_end]
            entry = self.IndexEntry(*(fields + (path.decode(),)))
            entries.append(entry)
            entry_len = ((62 + len(path) + 8) // 8) * 8
            i += entry_len
        assert len(entries) == num_entries
        return entries

    def ls_files(self, details=False):
        """Print list of files in index (including mode, SHA-1, and stage number
        if "details" is True).
        """
        for entry in self.read_index():
            if details:
                stage = (entry.flags >> 12) & 3
                print('{:6o} {} {:}\t{}'.format(
                        entry.mode, entry.sha1.hex(), stage, entry.path))
            else:
                print(entry.path)

    def get_status(self):
        """
        Get status of working copy, return tuple of (changed_paths, new_paths,
        deleted_paths).
        """
        paths = set()
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d != '.git']
            for file in files:
                path = os.path.join(root, file)
                path = path.replace('\\', '/')
                if path.startswith('./'):
                    path = path[2:]
                paths.add(path)
        entries_by_path = {e.path: e for e in self.read_index()}
        entry_paths = set(entries_by_path)
        changed = {p for p in (paths & entry_paths)
                if self.hash_object(utils.read_file(p), 'blob', write=False) !=
                    entries_by_path[p].sha1.hex()}
        new = paths - entry_paths
        deleted = entry_paths - paths
        return (sorted(changed), sorted(new), sorted(deleted))


    def status(self):
        """Show status of working copy."""
        changed, new, deleted = self.get_status()
        if changed:
            print('changed files:')
            for path in changed:
                print('   ', path)
        if new:
            print('new files:')
            for path in new:
                print('   ', path)
        if deleted:
            print('deleted files:')
            for path in deleted:
                print('   ', path)


    def diff(self):
        """Show diff of files changed (between index and working copy)."""
        changed, _, _ = self.get_status()
        entries_by_path = {e.path: e for e in self.read_index()}
        for i, path in enumerate(changed):
            sha1 = entries_by_path[path].sha1.hex()
            obj_type, data = self.read_object(sha1)
            assert obj_type == 'blob'
            index_lines = data.decode().splitlines()
            working_lines = utils.read_file(path).decode().splitlines()
            diff_lines = difflib.unified_diff(
                    index_lines, working_lines,
                    '{} (index)'.format(path),
                    '{} (working copy)'.format(path),
                    lineterm='')
            for line in diff_lines:
                print(line)
            if i < len(changed) - 1:
                print('-' * 70)

    def write_index(self, entries):
        """Write list of IndexEntry objects to git index file."""
        packed_entries = []
        for entry in entries:
            entry_head = struct.pack('!LLLLLLLLLL20sH',
                    entry.ctime_s, entry.ctime_n, entry.mtime_s, entry.mtime_n,
                    entry.dev, entry.ino, entry.mode, entry.uid, entry.gid,
                    entry.size, entry.sha1, entry.flags)
            path = entry.path.encode()
            length = ((62 + len(path) + 8) // 8) * 8
            packed_entry = entry_head + path + b'\x00' * (length - 62 - len(path))
            packed_entries.append(packed_entry)
        header = struct.pack('!4sLL', b'DIRC', 2, len(entries))
        all_data = header + b''.join(packed_entries)
        digest = hashlib.sha1(all_data).digest()
        utils.write_file(os.path.join(self.repo_path,'.git', 'index'), all_data + digest)

    # High level abstraction
    def add(self, paths):
        """Add all file paths to git index."""
        paths = [p.replace('\\', '/') for p in paths]
        all_entries = self.read_index()
        entries = [e for e in all_entries if e.path not in paths]
        for path in paths:
            path=os.path.join(self.repo_path, path)
            sha1 = self.hash_object(utils.read_file(path), 'blob')
            st = os.stat(path)
            flags = len(path.encode())
            assert flags < (1 << 12)
            # Init entry
            entry = self.IndexEntry(
                    int(st.st_ctime), 0, int(st.st_mtime), 0, st.st_dev,
                    st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_size,
                    bytes.fromhex(sha1), flags, path)
            entries.append(entry)
        entries.sort(key=operator.attrgetter('path'))
        self.write_index(entries)
        self._record_repo_operation('add')

    # ----------------------------------------------------------------
    # Commit Part
    # ----------------------------------------------------------------

    def write_tree(self):
        """Write a tree object from the current index entries, including subdirectories."""
        tree_entries = []
        entries_by_directory = collections.defaultdict(list)
        
        for entry in self.read_index():
            directory, filename = os.path.split(entry.path)
            entries_by_directory[directory].append((filename, entry))

            def write_tree_for_directory(directory):
                entries = entries_by_directory[directory]
                tree_contents = []
                for filename, entry in entries:
                    if os.path.join(directory, filename) in entries_by_directory:
                        mode = '40000'
                        sha1 = write_tree_for_directory(os.path.join(directory, filename))
                    else:
                        mode = '{:o}'.format(entry.mode)
                        sha1 = entry.sha1.hex()
                    tree_contents.append((mode, filename, sha1))
                tree_data = b''.join(b'%s %s\x00%s' % (mode.encode(), filename.encode(), bytes.fromhex(sha1))
                                    for mode, filename, sha1 in sorted(tree_contents))
                return self.hash_object(tree_data, 'tree')

        sha1 = write_tree_for_directory('')
        return sha1

    def read_tree(self, sha1=None, data=None):
        """Read tree object with given SHA-1 (hex string) or data, and return list
        of (mode, path, sha1) tuples.
        """
        if sha1 is not None:
            obj_type, data = self.read_object(sha1)
            assert obj_type == 'tree'
        elif data is None:
            raise TypeError('must specify "sha1" or "data"')
        i = 0
        entries = []
        for _ in range(1000):
            end = data.find(b'\x00', i)
            if end == -1:
                break
            mode_str, path = data[i:end].decode().split()
            mode = int(mode_str, 8)
            digest = data[end + 1:end + 21]
            entries.append((mode, path, digest.hex()))
            i = end + 1 + 20
        return entries

    def get_local_master_hash(self):
        """Get current commit hash (SHA-1 string) of local master branch."""
        master_path = os.path.join(self.repo_path,'.git', 'refs', 'heads', 'master')
        try:
            return utils.read_file(master_path).decode().strip()
        except FileNotFoundError:
            return None

    def commit(self, message, author):
        """
        Commit the current state of the index to master with given message.
        Return hash of commit object.
        """
        tree = self.write_tree()
        parent = self.get_local_master_hash()
        timestamp = int(time.mktime(time.localtime()))
        utc_offset = -time.timezone
        author_time = '{} {}{:02}{:02}'.format(
                timestamp,
                '+' if utc_offset > 0 else '-',
                abs(utc_offset) // 3600,
                (abs(utc_offset) // 60) % 60)
        lines = ['tree ' + tree]
        if parent:
            lines.append('parent ' + parent)
        lines.append('author {} {}'.format(author, author_time))
        lines.append('committer {} {}'.format(author, author_time))
        lines.append('')
        lines.append(message)
        lines.append('')
        data = '\n'.join(lines).encode()
        sha1 = self.hash_object(data, 'commit')
        master_path = os.path.join(self.repo_path,'.git', 'refs', 'heads', 'master')
        utils.write_file(master_path, (sha1 + '\n').encode())
        self._record_repo_operation('commit')
        print('committed to master: {:7}'.format(sha1))
        return sha1


    def finish(self):
        """Mark the repository as finished and record the finish time in the database."""
        self._record_repo_operation('finish')
        print('Repository finished: {}'.format(self.repo_path))

    def generate_summary(self, summary_file):
        """Generate a summary of the repository's lifecycle."""
        db = self._load_db()
        if self.repo_path in db:
            repo_info = db[self.repo_path]
            with open(summary_file, 'w') as file:
                file.write('Project Summary for: {}\n'.format(self.repo_path))
                file.write('Initialization time: {}\n'.format(repo_info['init_time']))
                file.write('Operations:\n')
                for op in repo_info['operations']:
                    file.write('  - Operation: {}, Time: {}\n'.format(op['operation'], op['time']))
                if repo_info['operations'] and repo_info['operations'][-1]['operation'] == 'finish':
                    init_time = datetime.datetime.fromisoformat(repo_info['init_time'])
                    finish_time = datetime.datetime.fromisoformat(repo_info['operations'][-1]['time'])
                    duration = finish_time - init_time
                    file.write('Completion time: {}\n'.format(repo_info['operations'][-1]['time']))
                    file.write('Total duration: {}\n'.format(str(duration)))
                print('Summary generated: {}'.format(summary_file))
        else:
            print('Error: Repository not found in database.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    sub_parsers = parser.add_subparsers(dest='command', metavar='command')
    sub_parsers.required = True

    parser.add_argument('--repo_path', help='Path to repo of git')

    sub_parser = sub_parsers.add_parser('add',
            help='add file(s) to index')
    sub_parser.add_argument('paths', nargs='+', metavar='path',
            help='path(s) of files to add')

    sub_parser = sub_parsers.add_parser('cat-file',
            help='display contents of object')
    valid_modes = ['commit', 'tree', 'blob', 'size', 'type', 'pretty']
    sub_parser.add_argument('mode', choices=valid_modes,
            help='object type (commit, tree, blob) or display mode (size, '
                 'type, pretty)')
    sub_parser.add_argument('hash_prefix',
            help='SHA-1 hash (or hash prefix) of object to display')

    sub_parser = sub_parsers.add_parser('commit',
            help='commit current state of index to master branch')
    sub_parser.add_argument('-a', '--author',
            help='commit author in format "A U Thor <author@example.com>" ')
    sub_parser.add_argument('-m', '--message', required=True,
            help='text of commit message')

    sub_parser = sub_parsers.add_parser('diff',
            help='show diff of files changed (between index and working '
                 'copy)')

    sub_parser = sub_parsers.add_parser('hash-object',
            help='hash contents of given path (and optionally write to '
                 'object store)')
    sub_parser.add_argument('path',
            help='path of file to hash')
    sub_parser.add_argument('-t', choices=['commit', 'tree', 'blob'],
            default='blob', dest='type',
            help='type of object (default %(default)r)')
    sub_parser.add_argument('-w', action='store_true', dest='write',
            help='write object to object store (as well as printing hash)')

    sub_parser = sub_parsers.add_parser('init',
            help='initialize a new repo')
    # sub_parser.add_argument('repo',
    #         help='directory name for new repo')

    sub_parser = sub_parsers.add_parser('ls-files',
            help='list files in index')
    sub_parser.add_argument('-s', '--stage', action='store_true',
            help='show object details (mode, hash, and stage number) in '
                 'addition to path')

    sub_parser = sub_parsers.add_parser('status',
            help='show status of working copy')
    
    sub_parser = sub_parsers.add_parser('finish',
        help='mark repository as finished and record the finish time')
    sub_parser = sub_parsers.add_parser('generate-summary',
            help='generate a summary of the repository\'s lifecycle')
    sub_parser.add_argument('summary_file', help='file path to write the project summary')


    args = parser.parse_args()
    gitd = Gitd(args.repo_path)
    if args.command == 'init':
        gitd.init()
    elif args.command == 'add':
        gitd.add(args.paths)
    elif args.command == 'cat-file':
        try:
            gitd.cat_file(args.mode, args.hash_prefix)
        except ValueError as error:
            print(error, file=sys.stderr)
            sys.exit(1)
    elif args.command == 'commit':
        gitd.commit(args.message, author=args.author)
    elif args.command == 'diff':
        gitd.diff()
    elif args.command == 'hash-object':
        sha1 = gitd.hash_object(utils.read_file(args.path), args.type, write=args.write)
        print(sha1)
    elif args.command == 'ls-files':
        gitd.ls_files(details=args.stage)
    elif args.command == 'status':
        gitd.status()
    elif args.command == 'finish':
        gitd.finish()
    elif args.command == 'generate-summary':
        gitd.generate_summary(args.summary_file)
    else:
        assert False, 'unexpected command {!r}'.format(args.command)