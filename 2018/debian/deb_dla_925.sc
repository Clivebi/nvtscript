if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890925" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2017-8296" );
	script_name( "Debian LTS: Security Advisory for kedpm (DLA-925-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-17 00:00:00 +0100 (Wed, 17 Jan 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/04/msg00045.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "kedpm on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', the master password disclosure issue has been
fixed in version 0.5.0-4+deb7u1. The entries issues has not been fixed
as it requires a rearchitecture of the software.

We recommend that you upgrade your kedpm packages. Note that kedpm has
been removed from the upcoming Debian release ('stretch') and you
should migrate to another password manager as kedpm was abandoned." );
	script_tag( name: "summary", value: "An information disclosure vulnerability was found in kedpm, a password
manager compatible with the figaro password manager file format. The
history file can reveal the master password if it is provided on the
commandline. The name of entries created or read in the password
manager are also exposed in the history file." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "kedpm", ver: "0.5.0-4+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "kedpm-gtk", ver: "0.5.0-4+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

