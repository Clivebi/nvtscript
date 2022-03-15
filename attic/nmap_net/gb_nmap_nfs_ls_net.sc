if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104076" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Nmap NSE net: nfs-ls" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Attempts to get useful information about files from NFS exports. The output is intended to resemble
the output of 'ls'.

The script starts by enumerating and mounting the remote NFS exports. After  that it performs an NFS
GETATTR procedure call for each mounted point in order to get its ACLs. For each mounted directory
the script will try to list its file entries with their attributes.

Since the file attributes shown in the results are the result of GETATTR, READDIRPLUS, and similar
procedures, the attributes are the attributes of the local filesystem.

These access permissions are shown only with NFSv3: * Read:     Read data from file or read a
directory. * Lookup:   Look up a name in a directory             (no meaning for non-directory
objects). * Modify:   Rewrite existing file data or modify existing             directory entries. *
Extend:   Write new data or add directory entries. * Delete:   Delete an existing directory entry. *
Execute:  Execute file (no meaning for a directory).

SYNTAX:

nfs.version:  number If set overrides the detected version of nfs


nfs-ls.human:  If set to '1' or 'true',
shows file sizes in a human readable format with suffixes like
'KB' and 'MB'.


nfs-ls.maxfiles:  If set, limits the amount of files returned by
the script when using the 'nfs-ls.dirlist' argument.
If set to 0
or less, all files are shown. The default value is 10.


nfs-ls.time:  Specifies which one of the last mac times to use in
the files attributes output. Possible values are:

  - 'm': last modification time (mtime)

  - 'a': last access time (atime)

  - 'c': last change time (ctime)
The default value is 'm' (mtime).


mount.version:  number If set overrides the detected version of mountd


rpc.protocol:  table If set overrides the preferred order in which
protocols are tested. (ie. 'tcp', 'udp')" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

