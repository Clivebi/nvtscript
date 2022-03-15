if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.0844.1" );
	script_cve_id( "CVE-2012-4481", "CVE-2013-1821", "CVE-2013-4073", "CVE-2013-4164" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:20 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-13 21:47:00 +0000 (Mon, 13 Aug 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:0844-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:0844-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20140844-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby' package(s) announced via the SUSE-SU-2014:0844-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Ruby received an LTSS roll-up update to fix the following security issues:

 * CVE-2012-4481: The safe-level feature in Ruby 1.8.7 allowed
 context-dependent attackers to modify strings via the NameError#to_s
 method when operating on Ruby objects.
 * CVE-2013-1821: A ruby entity expansion DoS vulnerability in REXML
 was fixed.
 * CVE-2013-4164: Fixed a heap overflow in float point parsing.
 * CVE-2013-4073: Fixed hostname check bypassing vulnerability in the
 SSL client.

Security Issues references:

 * CVE-2012-4481
 * CVE-2013-4073
 * CVE-2013-4164
 * CVE-2013-1821" );
	script_tag( name: "affected", value: "'ruby' package(s) on SUSE Linux Enterprise Server 11 SP1." );
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
if(release == "SLES11.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "ruby", rpm: "ruby~1.8.7.p357~0.9.15.6", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-doc-html", rpm: "ruby-doc-html~1.8.7.p357~0.9.15.6", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-tk", rpm: "ruby-tk~1.8.7.p357~0.9.15.6", rls: "SLES11.0SP1" ) )){
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

