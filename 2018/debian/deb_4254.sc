if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704254" );
	script_version( "2021-06-16T02:47:07+0000" );
	script_cve_id( "CVE-2018-10995", "CVE-2018-7033" );
	script_name( "Debian Security Advisory DSA 4254-1 (slurm-llnl - security update)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:47:07 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-24 00:00:00 +0200 (Tue, 24 Jul 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-28 20:20:00 +0000 (Thu, 28 Feb 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4254.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "slurm-llnl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 16.05.9-1+deb9u2.

We recommend that you upgrade your slurm-llnl packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/slurm-llnl" );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in the Simple Linux Utility for
Resource Management (SLURM), a cluster resource management and job
scheduling system. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2018-7033
Incomplete sanitization of user-provided text strings could lead to
SQL injection attacks against slurmdbd.

CVE-2018-10995
Insecure handling of user_name and gid fields leading to improper
authentication handling." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libpam-slurm", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpmi0", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpmi0-dbg", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpmi0-dev", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpmi2-0", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpmi2-0-dbg", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpmi2-0-dev", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurm-dev", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurm-perl", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurm30", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurm30-dbg", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurmdb-dev", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurmdb-perl", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurmdb30", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurmdb30-dbg", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-client", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-client-dbg", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-client-emulator", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-llnl", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-llnl-slurmdbd", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-wlm", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-wlm-basic-plugins", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-wlm-basic-plugins-dbg", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-wlm-basic-plugins-dev", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-wlm-doc", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-wlm-emulator", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-wlm-torque", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurmctld", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurmctld-dbg", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurmd", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurmd-dbg", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurmdbd", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurmdbd-dbg", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sview", ver: "16.05.9-1+deb9u2", rls: "DEB9" ) )){
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

