if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70614" );
	script_tag( name: "creation_date", value: "2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "FreeBSD Ports: phpldapadmin" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: phpldapadmin" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/106120/phpldapadmin-inject.txt" );
	script_xref( name: "URL", value: "http://sourceforge.net/tracker/?func=detail&aid=3417184&group_id=61828&atid=498546" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/edf47177-fe3f-11e0-a207-0014a5e3cda6.html" );
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
bver = portver( pkg: "phpldapadmin" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.2.0" ) >= 0 && revcomp( a: bver, b: "1.2.1.1_1,1" ) < 0){
	txt += "Package phpldapadmin version " + bver + " is installed which is known to be vulnerable.\n";
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

