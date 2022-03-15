if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72598" );
	script_cve_id( "CVE-2012-5533" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-11-26 12:47:32 -0500 (Mon, 26 Nov 2012)" );
	script_name( "FreeBSD Ports: lighttpd" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: lighttpd

CVE-2012-5533
The http_request_split_value function in request.c in lighttpd 1.4.32
allows remote attackers to cause a denial of service (infinite loop)
via a request with a header containing an empty token, as demonstrated
using the 'Connection: TE, , Keep-Alive' header." );
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
bver = portver( pkg: "lighttpd" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.4.30" ) > 0 && revcomp( a: bver, b: "1.4.32" ) < 0){
	txt += "Package lighttpd version " + bver + " is installed which is known to be vulnerable.\\n";
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

