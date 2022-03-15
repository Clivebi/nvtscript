if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71830" );
	script_cve_id( "CVE-2012-1613", "CVE-2012-1614" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "$Revision: 12214 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-05 15:42:52 +0100 (Mon, 05 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-30 11:34:17 -0400 (Thu, 30 Aug 2012)" );
	script_name( "FreeBSD Ports: coppermine" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: coppermine" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://forum.coppermine-gallery.net/index.php/topic,74682.0.html" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2012/q2/11" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/6dd5e45c-f084-11e1-8d0f-406186f3d89d.html" );
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
bver = portver( pkg: "coppermine" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.5.20" ) < 0){
	txt += "Package coppermine version " + bver + " is installed which is known to be vulnerable.\\n";
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

