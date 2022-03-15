if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71869" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2012-3981" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-09-07 11:47:17 -0400 (Fri, 07 Sep 2012)" );
	script_name( "FreeBSD Ports: bugzilla" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: bugzilla

CVE-2012-3981
Auth/Verify/LDAP.pm in Bugzilla 2.x and 3.x before 3.6.11, 3.7.x and
4.0.x before 4.0.8, 4.1.x and 4.2.x before 4.2.3, and 4.3.x before
4.3.3 does not restrict the characters in a username, which might
allow remote attackers to inject data into an LDAP directory via a
crafted login attempt." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "https://bugzilla.mozilla.org/show_bug.cgi?id=785470" );
	script_xref( name: "URL", value: "https://bugzilla.mozilla.org/show_bug.cgi?id=785522" );
	script_xref( name: "URL", value: "https://bugzilla.mozilla.org/show_bug.cgi?id=785511" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/6ad18fe5-f469-11e1-920d-20cf30e32f6d.html" );
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
bver = portver( pkg: "bugzilla" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.6.0" ) >= 0 && revcomp( a: bver, b: "3.6.11" ) < 0){
	txt += "Package bugzilla version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "4.0.0" ) >= 0 && revcomp( a: bver, b: "4.0.8" ) < 0){
	txt += "Package bugzilla version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "4.2.0" ) >= 0 && revcomp( a: bver, b: "4.2.3" ) < 0){
	txt += "Package bugzilla version " + bver + " is installed which is known to be vulnerable.\\n";
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

