if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71278" );
	script_cve_id( "CVE-2012-1906", "CVE-2012-1986", "CVE-2012-1987", "CVE-2012-1988", "CVE-2012-1989" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_version( "$Revision: 14170 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 10:24:12 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:59:26 -0400 (Mon, 30 Apr 2012)" );
	script_name( "FreeBSD Ports: puppet" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: puppet" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://puppetlabs.com/security/cve/cve-2012-1906/" );
	script_xref( name: "URL", value: "http://puppetlabs.com/security/cve/cve-2012-1986/" );
	script_xref( name: "URL", value: "http://puppetlabs.com/security/cve/cve-2012-1987/" );
	script_xref( name: "URL", value: "http://puppetlabs.com/security/cve/cve-2012-1988/" );
	script_xref( name: "URL", value: "http://puppetlabs.com/security/cve/cve-2012-1989/" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/607d2108-a0e4-423a-bf78-846f2a8f01b0.html" );
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
bver = portver( pkg: "puppet" );
if(!isnull( bver ) && revcomp( a: bver, b: "2.7.12_1" ) < 0){
	txt += "Package puppet version " + bver + " is installed which is known to be vulnerable.\\n";
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

