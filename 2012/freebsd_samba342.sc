if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71279" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-1182" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:59:26 -0400 (Mon, 30 Apr 2012)" );
	script_name( "FreeBSD Ports: samba34" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  samba34
   samba35
   samba36

CVE-2012-1182
The RPC code generator in Samba 3.x before 3.4.16, 3.5.x before
3.5.14, and 3.6.x before 3.6.4 does not implement validation of an
array length in a manner consistent with validation of array memory
allocation, which allows remote attackers to execute arbitrary code
via a crafted RPC call." );
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
bver = portver( pkg: "samba34" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.4" ) > 0 && revcomp( a: bver, b: "3.4.16" ) < 0){
	txt += "Package samba34 version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "samba35" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.5" ) > 0 && revcomp( a: bver, b: "3.5.14" ) < 0){
	txt += "Package samba35 version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "samba36" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.6" ) > 0 && revcomp( a: bver, b: "3.6.4" ) < 0){
	txt += "Package samba36 version " + bver + " is installed which is known to be vulnerable.\\n";
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

