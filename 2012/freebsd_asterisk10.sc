if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71537" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_cve_id( "CVE-2012-3553" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)" );
	script_name( "FreeBSD Ports: asterisk10" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: asterisk10

CVE-2012-3553
chan_skinny.c in the Skinny (aka SCCP) channel driver in Asterisk Open
Source 10.x before 10.5.1 allows remote authenticated users to cause a
denial of service (NULL pointer dereference and daemon crash) by
sending a Station Key Pad Button message and closing a connection in
off-hook mode, a related issue to CVE-2012-2948." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://downloads.digium.com/pub/security/AST-2012-009.html" );
	script_xref( name: "URL", value: "https://www.asterisk.org/security" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/3c8d1e5b-b673-11e1-be25-14dae9ebcf89.html" );
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
bver = portver( pkg: "asterisk10" );
if(!isnull( bver ) && revcomp( a: bver, b: "10" ) > 0 && revcomp( a: bver, b: "10.5.1" ) < 0){
	txt += "Package asterisk10 version " + bver + " is installed which is known to be vulnerable.\\n";
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

