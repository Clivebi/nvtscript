if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.0596.1" );
	script_cve_id( "CVE-2013-1788", "CVE-2013-1789", "CVE-2013-1790" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2014-01-28 04:51:00 +0000 (Tue, 28 Jan 2014)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:0596-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:0596-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20130596-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'poppler' package(s) announced via the SUSE-SU-2013:0596-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update of poppler fixes the following vulnerabilities:

 * CVE-2013-1788: Various invalid memory issues could be used by attackers supplying PDFs to crash the PDF viewer or potentially execute code.
 * CVE-2013-1789: A crash in poppler could be used by attackers providing PDFs to crash the PDF viewer.
 * CVE-2013-1790: An uninitialized memory read could be used by attackers providing PDFs to crash the PDF viewer.

Security Issue references:

 * CVE-2013-1788
>
 * CVE-2013-1789
>
 * CVE-2013-1790
>" );
	script_tag( name: "affected", value: "'poppler' package(s) on SUSE Linux Enterprise Desktop 11 SP2, SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Software Development Kit 11 SP2." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libpoppler-glib4", rpm: "libpoppler-glib4~0.12.3~1.8.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpoppler-qt4-3", rpm: "libpoppler-qt4-3~0.12.3~1.8.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpoppler5", rpm: "libpoppler5~0.12.3~1.8.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "poppler-tools", rpm: "poppler-tools~0.12.3~1.8.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

