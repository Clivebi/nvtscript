if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71289" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2012-0037" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:59:26 -0400 (Mon, 30 Apr 2012)" );
	script_name( "FreeBSD Ports: raptor2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  raptor2
   raptor" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2012/Mar/281" );
	script_xref( name: "URL", value: "http://www.vsecurity.com/resources/advisory/20120324-1/" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/60f81af3-7690-11e1-9423-00235a5f2c9a.html" );
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
bver = portver( pkg: "raptor2" );
if(!isnull( bver ) && revcomp( a: bver, b: "2.0.7" ) < 0){
	txt += "Package raptor2 version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "raptor" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.4.21_2" ) < 0){
	txt += "Package raptor version " + bver + " is installed which is known to be vulnerable.\\n";
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

