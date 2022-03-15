if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70261" );
	script_version( "2019-09-20T11:01:01+0000" );
	script_tag( name: "last_modification", value: "2019-09-20 11:01:01 +0000 (Fri, 20 Sep 2019)" );
	script_tag( name: "creation_date", value: "2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-2982", "CVE-2011-2981", "CVE-2011-2378", "CVE-2011-2984", "CVE-2011-2980", "CVE-2011-2983", "CVE-2011-2989", "CVE-2011-2991", "CVE-2011-2992", "CVE-2011-2985", "CVE-2011-2993", "CVE-2011-2988", "CVE-2011-2987", "CVE-2011-0084", "CVE-2011-2990", "CVE-2011-2986" );
	script_name( "FreeBSD Ports: firefox" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  firefox
   seamonkey
   linux-firefox
   thunderbird
   linux-thunderbird

For details, please visit the referenced advisories." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2011/mfsa2011-29.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2011/mfsa2011-30.html" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/834591a9-c82f-11e0-897d-6c626dd55a41.html" );
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
bver = portver( pkg: "firefox" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.6.*,1" ) > 0 && revcomp( a: bver, b: "3.6.20,1" ) < 0){
	txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "5.0.*,1" ) > 0 && revcomp( a: bver, b: "6.0,1" ) < 0){
	txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "seamonkey" );
if(!isnull( bver ) && revcomp( a: bver, b: "2.3" ) < 0){
	txt += "Package seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "linux-firefox" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.6.20,1" ) < 0){
	txt += "Package linux-firefox version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "thunderbird" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.1.12" ) < 0){
	txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "linux-thunderbird" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.1.12" ) < 0){
	txt += "Package linux-thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
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

