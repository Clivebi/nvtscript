if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70000" );
	script_version( "$Revision: 11768 $" );
	script_cve_id( "CVE-2011-4941" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 16:07:38 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "FreeBSD Ports: piwik" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: piwik" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://piwik.org/blog/2011/06/piwik-1-5-security-advisory/" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/23c8423e-9bff-11e0-8ea2-0019d18c446a.html" );
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
bver = portver( pkg: "piwik" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.2" ) >= 0 && revcomp( a: bver, b: "1.5" ) < 0){
	txt += "Package piwik version " + bver + " is installed which is known to be vulnerable.\n";
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

