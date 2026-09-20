from dataclasses import replace

from bulldog.filesystem_manifest import FilesystemManifest, ManifestEntry
from bulldog.snapshot import _content_hash, _identity_index


def test_directory_storage_size_is_not_content_but_file_size_is():
    directory = ManifestEntry('sub', 'directory', 1, 2, 0o755, 0, 0, 24, None)
    file = ManifestEntry('sub/input', 'file', 1, 3, 0o644, 0, 0, 4, 'a' * 64)
    source = FilesystemManifest('/source', 1, (directory, file))
    copied = replace(source, entries=(replace(directory, size=4096), file))
    assert _content_hash(source) == _content_hash(copied)
    assert _identity_index(source) != _identity_index(copied)
    assert _content_hash(source) != _content_hash(replace(source, entries=(directory, replace(file, size=5))))
