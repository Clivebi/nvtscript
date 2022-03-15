if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68834" );
	script_version( "$Revision: 11768 $" );
	script_cve_id( "CVE-2010-3436", "CVE-2010-3709" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 16:07:38 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "FreeBSD Ports: php5" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  php5

  php52" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.mail-archive.com/php-cvs@lists.php.net/msg47722.html" );
	script_xref( name: "URL", value: "http://www.php.net/releases/5_2_15.php" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/f3148a05-0fa7-11e0-becc-0022156e8794.html" );
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
bver = portver( pkg: "php5" );
if(!isnull( bver ) && revcomp( a: bver, b: "5.3.4" ) < 0){
	txt += "Package php5 version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "php52" );
if(!isnull( bver ) && revcomp( a: bver, b: "5.2.15" ) < 0){
	txt += "Package php52 version " + bver + " is installed which is known to be vulnerable.\n";
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

