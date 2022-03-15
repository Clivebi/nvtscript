if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69364" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "FreeBSD Ports: hiawatha" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: hiawatha" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.hiawatha-webserver.org/weblog/16" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43660/" );
	script_xref( name: "URL", value: "http://securityvulns.com/Zdocument902.html" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/99021/Hiawatha-WebServer-7.4-Denial-Of-Service.html" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2011/Mar/65" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/b13414c9-50ba-11e0-975a-000c29cc39d3.html" );
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
bver = portver( pkg: "hiawatha" );
if(!isnull( bver ) && revcomp( a: bver, b: "7.4_1" ) < 0){
	txt += "Package hiawatha version " + bver + " is installed which is known to be vulnerable.\n";
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

