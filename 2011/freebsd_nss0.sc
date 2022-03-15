if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70252" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "FreeBSD Ports: nss" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  nss

  ca_root_nss

  firefox

  seamonkey

  linux-firefox

  thunderbird

  linux-thunderbird

  linux-seamonkey" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.vasco.com/company/press_room/news_archive/2011/news_diginotar_reports_security_incident.aspx" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2011/mfsa2011-34.html" );
	script_xref( name: "URL", value: "http://googleonlinesecurity.blogspot.com/2011/08/update-on-attempted-man-in-middle.html" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/aa5bc971-d635-11e0-b3cf-080027ef73ec.html" );
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
bver = portver( pkg: "nss" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.12.11" ) < 0){
	txt += "Package nss version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "ca_root_nss" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.12.11" ) < 0){
	txt += "Package ca_root_nss version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "firefox" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.6.*,1" ) > 0 && revcomp( a: bver, b: "3.6.22,1" ) < 0){
	txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "4.0.*,1" ) > 0 && revcomp( a: bver, b: "6.0.2,1" ) < 0){
	txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "seamonkey" );
if(!isnull( bver ) && revcomp( a: bver, b: "2.3.2" ) < 0){
	txt += "Package seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "linux-firefox" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.6.22,1" ) < 0){
	txt += "Package linux-firefox version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "thunderbird" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.1" ) > 0 && revcomp( a: bver, b: "3.1.14" ) < 0){
	txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "5.0" ) > 0 && revcomp( a: bver, b: "6.0.2" ) < 0){
	txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "linux-thunderbird" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.1.14" ) < 0){
	txt += "Package linux-thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "linux-seamonkey" );
if(!isnull( bver ) && revcomp( a: bver, b: "2.3.2" ) < 0){
	txt += "Package linux-seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
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

