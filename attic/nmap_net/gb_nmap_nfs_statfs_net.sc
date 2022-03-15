if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104027" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Nmap NSE net: nfs-statfs" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Retrieves disk space statistics and information from a remote NFS share. The output is intended to
resemble the output of 'df'.

The script will provide pathconf information of the remote NFS if the version used is NFSv3.

SYNTAX:

nfs-statfs.human:  If set to '1' or 'true',
shows file sizes in a human readable format with suffixes like
'KB' and 'MB'.

mount.version:  number If set overrides the detected version of mountd

nfs.version:  number If set overrides the detected version of nfs

rpc.protocol:  table If set overrides the preferred order in which
protocols are tested. (ie. 'tcp', 'udp')" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

