if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70729" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-0806" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-12 07:27:19 -0500 (Sun, 12 Feb 2012)" );
	script_name( "FreeBSD Ports: bip" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: bip

CVE-2012-0806
Buffer overflow in Bip 0.8.8 and earlier might allow remote
authenticated users to execute arbitrary code via vectors involving a
series of TCP connections that triggers use of many open file
descriptors." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "https://projects.duckcorp.org/projects/bip/repository/revisions/222a33cb84a2e52ad55a88900b7895bf9dd0262c" );
	script_xref( name: "URL", value: "https://projects.duckcorp.org/issues/269" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/1c4cab30-5468-11e1-9fb7-003067b2972c.html" );
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
bver = portver( pkg: "bip" );
if(!isnull( bver ) && revcomp( a: bver, b: "0.8.8" ) <= 0){
	txt += "Package bip version " + bver + " is installed which is known to be vulnerable.\n";
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

