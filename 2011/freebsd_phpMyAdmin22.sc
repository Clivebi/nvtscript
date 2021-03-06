if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68698" );
	script_version( "$Revision: 14170 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 10:24:12 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2010-4329" );
	script_name( "FreeBSD Ports: phpMyAdmin" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  phpMyAdmin
   phpMyAdmin211

CVE-2010-4329
Cross-site scripting (XSS) vulnerability in the PMA_linkOrButton
function in libraries/common.lib.php in the database (db) search
script in phpMyAdmin 2.11.x before 2.11.11.1 and 3.x before 3.3.8.1
allows remote attackers to inject arbitrary web script or HTML via a
crafted request." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2010-8.php" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/753f8185-5ba9-42a4-be02-3f55ee580093.html" );
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
bver = portver( pkg: "phpMyAdmin" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.3.8.1" ) < 0){
	txt += "Package phpMyAdmin version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "phpMyAdmin211" );
if(!isnull( bver ) && revcomp( a: bver, b: "2.11.11.1" ) < 0){
	txt += "Package phpMyAdmin211 version " + bver + " is installed which is known to be vulnerable.\n";
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

