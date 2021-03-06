if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71366" );
	script_cve_id( "CVE-2012-2391" );
	script_version( "$Revision: 14170 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 10:24:12 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-05-31 11:53:50 -0400 (Thu, 31 May 2012)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "FreeBSD Ports: haproxy" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: haproxy" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "https://secunia.com/advisories/49261/" );
	script_xref( name: "URL", value: "http://haproxy.1wt.eu/download/1.4/src/CHANGELOG" );
	script_xref( name: "URL", value: "http://haproxy.1wt.eu/git?p=haproxy-1.4.git;a=commit;h=30297cb17147a8d339eb160226bcc08c91d9530a" );
	script_xref( name: "URL", value: "http://haproxy.1wt.eu/news.html" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/617959ce-a5f6-11e1-a284-0023ae8e59f0.html" );
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
bver = portver( pkg: "haproxy" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.4.21" ) < 0){
	txt += "Package haproxy version " + bver + " is installed which is known to be vulnerable.\\n";
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

