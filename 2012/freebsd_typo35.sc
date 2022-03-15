if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71527" );
	script_version( "$Revision: 11768 $" );
	script_cve_id( "CVE-2012-3414" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 16:07:38 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "FreeBSD Ports: typo3" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: typo3" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49780/" );
	script_xref( name: "URL", value: "https://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2012-003/" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/c28ee9cd-916e-4dcf-8ed3-e97e5846db6c.html" );
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
bver = portver( pkg: "typo3" );
if(!isnull( bver ) && revcomp( a: bver, b: "4.5" ) >= 0 && revcomp( a: bver, b: "4.5.17" ) < 0){
	txt += "Package typo3 version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "4.6" ) >= 0 && revcomp( a: bver, b: "4.6.10" ) < 0){
	txt += "Package typo3 version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "4.7" ) >= 0 && revcomp( a: bver, b: "4.7.2" ) < 0){
	txt += "Package typo3 version " + bver + " is installed which is known to be vulnerable.\\n";
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

