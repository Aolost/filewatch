module github.com/Aolost/filewatch

// Go 1.24 is required for os.Root, which gives race-free, root-confined
// file access (openat-based on Unix). See README "Platform notes".
go 1.24
