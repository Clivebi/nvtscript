if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.53944" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_cve_id( "CVE-2003-0985", "CVE-2004-0077" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 14202 $" );
	script_name( "Slackware Advisory SSA:2004-049-01 Kernel security update " );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK9\\.1" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2004-049-01" );
	script_tag( name: "insight", value: "New kernels are available for Slackware 9.1 and -current to fix
a bounds-checking problem in the kernel's mremap() call which
could be used by a local attacker to gain root privileges.
Please note that this is not the same issue as CVE-2003-0985
which was fixed in early January.

The kernels in Slackware 8.1 and 9.0 that were updated in
January are not vulnerable to this new issue because the patch
from Solar Designer that was used to fix the CVE-2003-0985 bugs
also happened to fix the problem that was discovered later.

Sites running Slackware 9.1 or -current should upgrade to a
new kernel.  After installing the new kernel, be sure to run
'lilo'." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2004-049-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "kernel-ide", ver: "2.4.24-i486-2", rls: "SLK9.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "kernel-source", ver: "2.4.24-noarch-2", rls: "SLK9.1" ) ) != NULL){
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

