if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1427" );
	script_cve_id( "CVE-2010-0743", "CVE-2010-2221" );
	script_tag( name: "creation_date", value: "2020-01-23 11:45:01 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-19 01:30:00 +0000 (Tue, 19 Sep 2017)" );
	script_name( "Huawei EulerOS: Security Advisory for scsi-target-utils (EulerOS-SA-2019-1427)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.1\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1427" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1427" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'scsi-target-utils' package(s) announced via the EulerOS-SA-2019-1427 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple buffer overflows in the iSNS implementation in isns.c in (1) Linux SCSI target framework (aka tgt or scsi-target-utils) before 1.0.6, (2) iSCSI Enterprise Target (aka iscsitarget or IET) 1.4.20.1 and earlier, and (3) Generic SCSI Target Subsystem for Linux (aka SCST or iscsi-scst) 1.0.1.1 and earlier allow remote attackers to cause a denial of service (memory corruption and daemon crash) or possibly execute arbitrary code via (a) a long iSCSI Name string in an SCN message or (b) an invalid PDU.(CVE-2010-2221)

Multiple format string vulnerabilities in isns.c in (1) Linux SCSI target framework (aka tgt or scsi-target-utils) 1.0.3, 0.9.5, and earlier and (2) iSCSI Enterprise Target (aka iscsitarget) 0.4.16 allow remote attackers to cause a denial of service (tgtd daemon crash) or possibly have unspecified other impact via vectors that involve the isns_attr_query and qry_rsp_handle functions, and are related to (a) client appearance and (b) client disappearance messages.(CVE-2010-0743)" );
	script_tag( name: "affected", value: "'scsi-target-utils' package(s) on Huawei EulerOS Virtualization 3.0.1.0." );
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
if(release == "EULEROSVIRT-3.0.1.0"){
	if(!isnull( res = isrpmvuln( pkg: "scsi-target-utils", rpm: "scsi-target-utils~1.0.70~4.h3", rls: "EULEROSVIRT-3.0.1.0" ) )){
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

