if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71380" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-0946", "CVE-2012-4225" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-05-31 11:53:51 -0400 (Thu, 31 May 2012)" );
	script_name( "FreeBSD Ports: nvidia-driver" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: nvidia-driver

CVE-2012-0946
The NVIDIA UNIX driver before 295.40 allows local users to access
arbitrary memory locations by leveraging GPU device-node read/write
privileges." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
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
bver = portver( pkg: "nvidia-driver" );
if(!isnull( bver ) && revcomp( a: bver, b: "173.14.31_1" ) > 0 && revcomp( a: bver, b: "295.40" ) < 0){
	txt += "Package nvidia-driver version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "100.14.03" ) >= 0 && revcomp( a: bver, b: "173.14.31_1" ) < 0){
	txt += "Package nvidia-driver version " + bver + " is installed which is known to be vulnerable.\\n";
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
