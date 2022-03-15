if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72501" );
	script_cve_id( "CVE-2012-4524" );
	script_version( "2021-08-27T12:28:31+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 12:28:31 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-10-22 08:43:21 -0400 (Mon, 22 Oct 2012)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-04 14:54:00 +0000 (Wed, 04 Dec 2019)" );
	script_name( "FreeBSD Ports: xlockmore, ja-xlockmore" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc." );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  xlockmore
   ja-xlockmore

CVE-2012-4524
** RESERVED **
This candidate has been reserved by an organization or individual that
will use it when announcing a new security problem.  When the
candidate has been publicized, the details for this candidate will be
provided." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2012/10/17/10" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/57652765-18aa-11e2-8382-00a0d181e71d.html" );
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
bver = portver( pkg: "xlockmore" );
if(!isnull( bver ) && revcomp( a: bver, b: "5.40_1" ) < 0){
	txt += "Package xlockmore version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "ja-xlockmore" );
if(!isnull( bver ) && revcomp( a: bver, b: "5.40_1" ) < 0){
	txt += "Package ja-xlockmore version " + bver + " is installed which is known to be vulnerable.\\n";
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

