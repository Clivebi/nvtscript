if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70761" );
	script_cve_id( "CVE-2012-0070" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_version( "2021-08-27T12:57:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 12:57:20 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-23 17:25:00 +0000 (Thu, 23 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-02-12 07:27:20 -0500 (Sun, 12 Feb 2012)" );
	script_name( "FreeBSD Ports: spamdyke" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc." );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: spamdyke" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47435/" );
	script_xref( name: "URL", value: "http://www.spamdyke.org/documentation/Changelog.txt" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/a47af810-3a17-11e1-a1be-00e0815b8da8.html" );
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
bver = portver( pkg: "spamdyke" );
if(!isnull( bver ) && revcomp( a: bver, b: "4.2.1" ) < 0){
	txt += "Package spamdyke version " + bver + " is installed which is known to be vulnerable.\n";
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

