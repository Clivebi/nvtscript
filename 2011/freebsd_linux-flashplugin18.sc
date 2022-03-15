if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70268" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-2130", "CVE-2011-2134", "CVE-2011-2135", "CVE-2011-2136", "CVE-2011-2137", "CVE-2011-2138", "CVE-2011-2139", "CVE-2011-2140", "CVE-2011-2414", "CVE-2011-2415", "CVE-2011-2416", "CVE-2011-2417", "CVE-2011-2425" );
	script_name( "FreeBSD Ports: linux-flashplugin" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  linux-flashplugin
   linux-f10-flashplugin" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "https://www.adobe.com/support/security/bulletins/apsb11-21.html" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/2c12ae0c-c38d-11e0-8eb7-001b2134ef46.html" );
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
bver = portver( pkg: "linux-flashplugin" );
if(!isnull( bver ) && revcomp( a: bver, b: "9.0r289" ) <= 0){
	txt += "Package linux-flashplugin version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "linux-f10-flashplugin" );
if(!isnull( bver ) && revcomp( a: bver, b: "10.3r183.5" ) < 0){
	txt += "Package linux-f10-flashplugin version " + bver + " is installed which is known to be vulnerable.\n";
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

