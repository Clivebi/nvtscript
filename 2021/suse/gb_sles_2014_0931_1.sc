if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.0931.1" );
	script_cve_id( "CVE-2014-3467", "CVE-2014-3468", "CVE-2014-3469" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:16 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-16 14:30:00 +0000 (Mon, 16 Nov 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:0931-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:0931-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20140931-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libtasn1' package(s) announced via the SUSE-SU-2014:0931-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "libtasn1 has been updated to fix three security issues:

 * asn1_get_bit_der() could have returned negative bit length
 (CVE-2014-3468)
 * Multiple boundary check issues could have allowed DoS (CVE-2014-3467)
 * Possible DoS by NULL pointer dereference in asn1_read_value_type
 (CVE-2014-3469)

Security Issues:

 * CVE-2014-3468
 * CVE-2014-3467
 * CVE-2014-3469" );
	script_tag( name: "affected", value: "'libtasn1' package(s) on SUSE Linux Enterprise Desktop 11 SP3, SUSE Linux Enterprise Server 11 SP3, SUSE Linux Enterprise Software Development Kit 11 SP3." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "libtasn1", rpm: "libtasn1~1.5~1.28.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtasn1-3", rpm: "libtasn1-3~1.5~1.28.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtasn1-3-32bit", rpm: "libtasn1-3-32bit~1.5~1.28.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtasn1-3-x86", rpm: "libtasn1-3-x86~1.5~1.28.1", rls: "SLES11.0SP3" ) )){
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

