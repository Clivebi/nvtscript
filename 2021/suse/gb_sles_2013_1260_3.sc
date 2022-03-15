if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.1260.3" );
	script_cve_id( "CVE-2013-4073" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:24 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-13 21:47:00 +0000 (Mon, 13 Aug 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:1260-3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP2|SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:1260-3" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20131260-3/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby' package(s) announced via the SUSE-SU-2013:1260-3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Ruby failed to check hostnames correctly when setting up a SSL client connection. CVE-2013-4073 was assigned to this issue.

Security Issue reference:

 * CVE-2013-4073
>" );
	script_tag( name: "affected", value: "'ruby' package(s) on SUSE Lifecycle Management Server 1.3, SUSE Linux Enterprise Desktop 11 SP2, SUSE Linux Enterprise Desktop 11 SP3, SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Server 11 SP3, SUSE Linux Enterprise Software Development Kit 11 SP2, SUSE Linux Enterprise Software Development Kit 11 SP3, WebYaST 1.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "ruby", rpm: "ruby~1.8.7.p357~0.9.11.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-doc-html", rpm: "ruby-doc-html~1.8.7.p357~0.9.11.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-tk", rpm: "ruby-tk~1.8.7.p357~0.9.11.1", rls: "SLES11.0SP2" ) )){
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "ruby", rpm: "ruby~1.8.7.p357~0.9.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-doc-html", rpm: "ruby-doc-html~1.8.7.p357~0.9.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-tk", rpm: "ruby-tk~1.8.7.p357~0.9.11.1", rls: "SLES11.0SP3" ) )){
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

