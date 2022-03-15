if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71868" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2012-3789" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-09-07 11:47:17 -0400 (Fri, 07 Sep 2012)" );
	script_name( "FreeBSD Ports: bitcoin" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: bitcoin

CVE-2012-3789
Unspecified vulnerability in bitcoind and Bitcoin-Qt before 0.4.7rc3,
0.5.x before 0.5.6rc3, 0.6.0.x before 0.6.0.9rc1, and 0.6.x before
0.6.3rc1 allows remote attackers to cause a denial of service (process
hang) via unknown behavior on a Bitcoin network." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "https://bitcointalk.org/?topic=88734" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/b50913ce-f4a7-11e1-b135-003067b2972c.html" );
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
bver = portver( pkg: "bitcoin" );
if(!isnull( bver ) && revcomp( a: bver, b: "0.6.3" ) < 0){
	txt += "Package bitcoin version " + bver + " is installed which is known to be vulnerable.\\n";
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
