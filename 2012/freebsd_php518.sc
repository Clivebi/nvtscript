if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71521" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-2688" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)" );
	script_name( "FreeBSD Ports: php5" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  php5
   php53
   php52

CVE-2012-2688
Unspecified vulnerability in the _php_stream_scandir function in the
stream implementation in PHP before 5.3.15 and 5.4.x before 5.4.5 has
unknown impact and remote attack vectors, related to an 'overflow.'" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.php.net/archive/2012.php#id2012-07-19-1" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/bdab0acd-d4cd-11e1-8a1c-14dae9ebcf89.html" );
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
if(!isnull( bver ) && revcomp( a: bver, b: "5.4" ) > 0 && revcomp( a: bver, b: "5.4.5" ) < 0){
	txt += "Package php5 version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "php53" );
if(!isnull( bver ) && revcomp( a: bver, b: "5.3.15" ) < 0){
	txt += "Package php53 version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "php52" );
if(!isnull( bver ) && revcomp( a: bver, b: "5.2.17_10" ) <= 0){
	txt += "Package php52 version " + bver + " is installed which is known to be vulnerable.\\n";
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

