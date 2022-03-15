if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70260" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_cve_id( "CVE-2011-2746" );
	script_name( "FreeBSD Ports: otrs" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: otrs

CVE-2011-2746
Unspecified vulnerability in Kernel/Modules/AdminPackageManager.pm in
OTRS-Core in Open Ticket Request System (OTRS) 2.x before 2.4.11 and
3.x before 3.0.10 allows remote authenticated administrators to read
arbitrary files via unknown vectors." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://otrs.org/advisory/OSA-2011-03-en/" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/86baa0d4-c997-11e0-8a8e-00151735203a.html" );
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
bver = portver( pkg: "otrs" );
if(!isnull( bver ) && revcomp( a: bver, b: "2.1" ) > 0 && revcomp( a: bver, b: "3.0.10" ) < 0){
	txt += "Package otrs version " + bver + " is installed which is known to be vulnerable.\n";
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

