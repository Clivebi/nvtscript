if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69600" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2011-1518" );
	script_name( "FreeBSD Ports: otrs" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: otrs

CVE-2011-1518
Multiple cross-site scripting (XSS) vulnerabilities in Open Ticket
Request System (OTRS) 2.4.x before 2.4.10 and 3.x before 3.0.7 allow
remote attackers to inject arbitrary web script or HTML via
unspecified vectors." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://otrs.org/advisory/OSA-2011-01-en/" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/a4372a68-652c-11e0-a25a-00151735203a.html" );
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
bver = portver( pkg: "otrs" );
if(!isnull( bver ) && revcomp( a: bver, b: "2.3" ) > 0 && revcomp( a: bver, b: "3.0.7" ) < 0){
	txt += "Package otrs version " + bver + " is installed which is known to be vulnerable.\n";
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

