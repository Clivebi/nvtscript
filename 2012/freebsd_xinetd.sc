if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72502" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2012-0862" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-10-22 08:43:21 -0400 (Mon, 22 Oct 2012)" );
	script_name( "FreeBSD Ports: xinetd" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: xinetd

CVE-2012-0862
builtins.c in Xinetd before 2.3.15 does not check the service type
when the tcpmux-server service is enabled, which exposes all enabled
services and allows remote attackers to bypass intended access
restrictions via a request to tcpmux port 1." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=790940" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/e11955ca-187c-11e2-be36-00215af774f0.html" );
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
bver = portver( pkg: "xinetd" );
if(!isnull( bver ) && revcomp( a: bver, b: "2.3.15" ) < 0){
	txt += "Package xinetd version " + bver + " is installed which is known to be vulnerable.\\n";
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

