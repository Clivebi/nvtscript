if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68701" );
	script_version( "$Revision: 14170 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 10:24:12 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "FreeBSD Ports: horde-base" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: horde-base" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://article.gmane.org/gmane.comp.horde.announce/532" );
	script_xref( name: "URL", value: "http://bugs.horde.org/ticket/9357" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/a3314314-f731-11df-a757-0011098ad87f.html" );
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
bver = portver( pkg: "horde-base" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.3.11" ) < 0){
	txt += "Package horde-base version " + bver + " is installed which is known to be vulnerable.\n";
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

