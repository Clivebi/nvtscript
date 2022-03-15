if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68828" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-3709" );
	script_name( "FreeBSD Ports: php5-zip" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  php5-zip
   php52-zip

CVE-2010-3709
The ZipArchive::getArchiveComment function in PHP 5.2.x through 5.2.14
and 5.3.x through 5.3.3 allows context-dependent attackers to cause a
denial of service (NULL pointer dereference and application crash) via
a crafted ZIP archive." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.php.net/releases/5_3_4.php" );
	script_xref( name: "URL", value: "http://www.php.net/releases/5_2_15.php" );
	script_xref( name: "URL", value: "http://securityreason.com/achievement_securityalert/90" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/2a41233d-10e7-11e0-becc-0022156e8794.html" );
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
bver = portver( pkg: "php5-zip" );
if(!isnull( bver ) && revcomp( a: bver, b: "5.3.4" ) < 0){
	txt += "Package php5-zip version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "php52-zip" );
if(!isnull( bver ) && revcomp( a: bver, b: "5.2.15" ) < 0){
	txt += "Package php52-zip version " + bver + " is installed which is known to be vulnerable.\n";
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

