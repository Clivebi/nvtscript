if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.53937" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_cve_id( "CVE-2004-0394", "CVE-2004-0424" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 14202 $" );
	script_name( "Slackware Advisory SSA:2004-119-01 kernel security updates" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK9\\.1" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2004-119-01" );
	script_tag( name: "insight", value: "New kernel packages are available for Slackware 9.1 and -current to
fix security issues.  Also available are new kernel modules packages
(including alsa-driver), and a new version of the hotplug package
for Slackware 9.1 containing some fixes for using 2.4.26 (and 2.6.x)
kernel modules.

The most serious of the fixed issues is an overflow in ip_setsockopt(),
which could allow a local attacker to gain root access, or to crash or
reboot the machine.  This bug affects 2.4 kernels from 2.4.22 - 2.4.25.
Any sites running one of those kernel versions should upgrade right
away.  After installing the new kernel, be sure to run 'lilo'." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2004-119-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "alsa-driver", ver: "0.9.8-i486-3", rls: "SLK9.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "hotplug", ver: "2004_01_05-noarch-1", rls: "SLK9.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "kernel-ide", ver: "2.4.26-i486-2", rls: "SLK9.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "kernel-headers", ver: "2.4.26-i386-1", rls: "SLK9.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "kernel-modules", ver: "2.4.26-i486-1", rls: "SLK9.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "kernel-source", ver: "2.4.26-noarch-1", rls: "SLK9.1" ) ) != NULL){
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

