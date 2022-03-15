if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71386" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-3078", "CVE-2011-3079", "CVE-2011-3080", "CVE-2011-3081", "CVE-2012-1521" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-05-31 11:53:51 -0400 (Thu, 31 May 2012)" );
	script_name( "FreeBSD Ports: chromium" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: chromium

CVE-2011-3078
Use-after-free vulnerability in Google Chrome before 18.0.1025.168
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to the floating of
elements, a different vulnerability than CVE-2011-3081.
CVE-2011-3079
The Inter-process Communication (IPC) implementation in Google Chrome
before 18.0.1025.168 does not properly validate messages, which has
unspecified impact and attack vectors.
CVE-2011-3080
Race condition in the Inter-process Communication (IPC) implementation
in Google Chrome before 18.0.1025.168 allows attackers to bypass
intended sandbox restrictions via unspecified vectors.
CVE-2011-3081
Use-after-free vulnerability in Google Chrome before 18.0.1025.168
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to the floating of
elements, a different vulnerability than CVE-2011-3078.
CVE-2012-1521
Use-after-free vulnerability in the XML parser in Google Chrome before
18.0.1025.168 allows remote attackers to cause a denial of service or
possibly have unspecified other impact via unknown vectors." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/search/label/Stable%20updates" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/94c0ac4f-9388-11e1-b242-00262d5ed8ee.html" );
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
bver = portver( pkg: "chromium" );
if(!isnull( bver ) && revcomp( a: bver, b: "18.0.1025.168" ) < 0){
	txt += "Package chromium version " + bver + " is installed which is known to be vulnerable.\\n";
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

