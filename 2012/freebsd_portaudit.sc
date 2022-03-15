if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71156" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-03-12 11:35:07 -0400 (Mon, 12 Mar 2012)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "FreeBSD Ports: portaudit" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: portaudit" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://cvsweb.FreeBSD.org/ports/ports-mgmt/portaudit/Makefile#rev1.30" );
	script_xref( name: "URL", value: "http://cvsweb.FreeBSD.org/ports/Mk/bsd.port.mk#rev1.707" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/6d329b64-6bbb-11e1-9166-001e4f0fb9b1.html" );
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
bver = portver( pkg: "portaudit" );
if(!isnull( bver ) && revcomp( a: bver, b: "0.6.0" ) < 0){
	txt += "Package portaudit version " + bver + " is installed which is known to be vulnerable.\\n";
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

