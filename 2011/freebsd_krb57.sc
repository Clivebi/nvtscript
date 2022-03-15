if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68693" );
	script_version( "2021-05-19T13:10:04+0000" );
	script_tag( name: "last_modification", value: "2021-05-19 13:10:04 +0000 (Wed, 19 May 2021)" );
	script_tag( name: "creation_date", value: "2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-21 15:46:00 +0000 (Tue, 21 Jan 2020)" );
	script_cve_id( "CVE-2010-1324" );
	script_bugtraq_id( 45116 );
	script_name( "FreeBSD Ports: krb5" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: krb5

CVE-2010-1324
MIT Kerberos 5 (aka krb5) 1.7.x and 1.8.x through 1.8.3 does not
properly determine the acceptability of checksums, which might allow
remote attackers to forge GSS tokens, gain privileges, or have
unspecified other impact via (1) an unkeyed checksum, (2) an unkeyed
PAC checksum, or (3) a KrbFastArmoredReq checksum based on an RC4 key." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
software upgrades." );
	script_tag( name: "summary", value: "The remote host is missing an update to the system
as announced in the referenced advisory." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2010-007.txt" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/9f971cea-03f5-11e0-bf50-001a926c7637.html" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-bsd.inc.sc");
txt = "";
vuln = FALSE;
bver = portver( pkg: "krb5" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.7.0" ) >= 0 && revcomp( a: bver, b: "1.8.0" ) < 0){
	txt += "Package krb5 version " + bver + " is installed which is known to be vulnerable.\n";
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

