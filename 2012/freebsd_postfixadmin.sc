if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70744" );
	script_cve_id( "CVE-2012-0811", "CVE-2012-0812" );
	script_version( "2019-11-29T08:04:17+0000" );
	script_tag( name: "last_modification", value: "2019-11-29 08:04:17 +0000 (Fri, 29 Nov 2019)" );
	script_tag( name: "creation_date", value: "2012-02-12 07:27:20 -0500 (Sun, 12 Feb 2012)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "FreeBSD Ports: postfixadmin" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: postfixadmin" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/postfixadmin/forums/forum/676076/topic/4977778" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/93688f8f-4935-11e1-89b4-001ec9578670.html" );
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
bver = portver( pkg: "postfixadmin" );
if(!isnull( bver ) && revcomp( a: bver, b: "2.3.5" ) < 0){
	txt += "Package postfixadmin version " + bver + " is installed which is known to be vulnerable.\n";
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

