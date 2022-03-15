if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891367" );
	script_version( "2021-06-21T11:00:26+0000" );
	script_cve_id( "CVE-2018-7033" );
	script_name( "Debian LTS: Security Advisory for slurm-llnl (DLA-1367-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 11:00:26 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-29 00:00:00 +0200 (Sun, 29 Apr 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-28 20:20:00 +0000 (Thu, 28 Feb 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/04/msg00032.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "slurm-llnl on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
2.3.4-2+deb7u2.

We recommend that you upgrade your slurm-llnl packages." );
	script_tag( name: "summary", value: "CVE-2018-7033
An issue that could be used for SQL Injection attacks against
SlurmDBD has been fixed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libpam-slurm", ver: "2.3.4-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpmi0", ver: "2.3.4-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpmi0-dev", ver: "2.3.4-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurm-dev", ver: "2.3.4-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurm-perl", ver: "2.3.4-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurm23", ver: "2.3.4-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurmdb-dev", ver: "2.3.4-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurmdb-perl", ver: "2.3.4-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurmdb23", ver: "2.3.4-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-llnl", ver: "2.3.4-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-llnl-basic-plugins", ver: "2.3.4-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-llnl-basic-plugins-dev", ver: "2.3.4-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-llnl-doc", ver: "2.3.4-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-llnl-slurmdbd", ver: "2.3.4-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-llnl-sview", ver: "2.3.4-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-llnl-torque", ver: "2.3.4-2+deb7u2", rls: "DEB7" ) )){
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

