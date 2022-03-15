if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892143" );
	script_version( "2021-08-13T07:21:38+0000" );
	script_cve_id( "CVE-2019-12838", "CVE-2019-6438" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 07:21:38 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-24 03:15:00 +0000 (Wed, 24 Jul 2019)" );
	script_tag( name: "creation_date", value: "2020-03-18 10:44:54 +0000 (Wed, 18 Mar 2020)" );
	script_name( "Debian LTS: Security Advisory for slurm-llnl (DLA-2143-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/03/msg00016.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2143-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/920997" );
	script_xref( name: "URL", value: "https://bugs.debian.org/931880" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'slurm-llnl'
  package(s) announced via the DLA-2143-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several issues were found in Simple Linux Utility for Resource
Management (SLURM), a cluster resource management and job scheduling
system.

CVE-2019-6438

SchedMD Slurm mishandles 32-bit systems, causing a heap overflow
in xmalloc.

CVE-2019-12838

SchedMD Slurm did not escape strings when importing an archive
file into the accounting_storage/mysql backend, resulting in SQL
injection." );
	script_tag( name: "affected", value: "'slurm-llnl' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
14.03.9-5+deb8u5.

We recommend that you upgrade your slurm-llnl packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libpam-slurm", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpmi0", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpmi0-dev", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurm-dev", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurm-perl", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurm27", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurmdb-dev", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurmdb-perl", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libslurmdb27", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-client", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-llnl", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-llnl-slurmdbd", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-wlm", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-wlm-basic-plugins", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-wlm-basic-plugins-dev", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-wlm-doc", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurm-wlm-torque", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurmctld", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurmd", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slurmdbd", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sview", ver: "14.03.9-5+deb8u5", rls: "DEB8" ) )){
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
exit( 0 );

