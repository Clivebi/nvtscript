if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70603" );
	script_tag( name: "creation_date", value: "2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_cve_id( "CVE-2011-4107" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_version( "$Revision: 11762 $" );
	script_name( "FreeBSD Ports: phpMyAdmin" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: phpMyAdmin

CVE-2011-4107
The simplexml_load_string function in the XML import plug-in
(libraries/import/xml.php) in phpMyAdmin 3.4.x before 3.4.7.1 and
3.3.x before 3.3.10.5 allows remote authenticated users to read
arbitrary files via XML data containing external entity references,
aka an XML external entity (XXE) injection attack." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2011-17.php" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/1f6ee708-0d22-11e1-b5bd-14dae938ec40.html" );
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
if(!isnull( bver ) && revcomp( a: bver, b: "3.4" ) > 0 && revcomp( a: bver, b: "3.4.7.1" ) < 0){
	txt += "Package phpMyAdmin version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "3.3.10.5" ) < 0){
	txt += "Package phpMyAdmin version " + bver + " is installed which is known to be vulnerable.\n";
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

