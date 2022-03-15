if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71530" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-0217" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)" );
	script_name( "FreeBSD Ports: FreeBSD" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: FreeBSD

CVE-2012-0217
The x86-64 kernel system-call functionality in Xen 4.1.2 and earlier,
as used in Citrix XenServer 6.0.2 and earlier and other products,
Oracle Solaris 11 and earlier, illumos before r13724, Joyent SmartOS
before 20120614T184600Z, FreeBSD before 9.0-RELEASE-p3, NetBSD 6.0
Beta and earlier, and Microsoft Windows Server 2008 R2 and R2 SP1 and
Windows 7 Gold and SP1, when running on an Intel processor,
incorrectly uses the sysret path in cases where a certain address is
not a canonical address, which allows local users to gain privileges
via a crafted application.  NOTE: this description clearly does not
belong in CVE, because a single entry cannot be about independent
codebases. However, there was some value in preserving the original
mapping of the multi-codebase coordinated-disclosure effort to a
single identifier." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_tag( name: "summary", value: "The remote host is missing an update to the system
  as announced in the referenced advisory." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-bsd.inc.sc");
vuln = FALSE;
txt = "";
bver = portver( pkg: "FreeBSD" );
if(!isnull( bver ) && revcomp( a: bver, b: "7.4" ) >= 0 && revcomp( a: bver, b: "7.4_9" ) < 0){
	txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "8.1" ) >= 0 && revcomp( a: bver, b: "8.1_12" ) < 0){
	txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "8.2" ) >= 0 && revcomp( a: bver, b: "8.2_9" ) < 0){
	txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "8.3" ) >= 0 && revcomp( a: bver, b: "8.3_3" ) < 0){
	txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "9.0" ) >= 0 && revcomp( a: bver, b: "9.0_3" ) < 0){
	txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if( vuln ){
	security_message( data: txt );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

