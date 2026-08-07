'use strict';

/**
 * Copyright 2022 Adobe. All rights reserved.
 * This file is licensed to you under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
 * OF ANY KIND, either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */

const mongoSanitize = require('express-mongo-sanitize');
const cSchema = require('./censys_schema2');

// CensysModel
module.exports = {
    CensysModel: cSchema.censysModel,
    getRecordByIpPromise: function (ip) {
        return cSchema.censysModel.find({ 'ip': ip }).exec();
    },
    getRecordByIpRangePromise: function (ipRange) {
        let reZone = new RegExp('^' + ipRange + '\\..*');
        return cSchema.censysModel.find({
            'ip': mongoSanitize.sanitize({ data: { '$regex': reZone } }).data,
        }).exec();
    },
    getRecordsByZonePromise: function (zone, count) {
        let promise;
        if (count) {
            promise = cSchema.censysModel.countDocuments({ 'zones': zone }).exec();
        } else {
            promise = cSchema.censysModel.find({ 'zones': mongoSanitize.sanitize({ data: zone }).data }).exec();
        }
        return (promise);
    },
    getPortCountPromise: function (port) {
        let pPort = 'p' + port;
        return cSchema.censysModel.find({}).exists(pPort).countDocuments().exec();
    },
    getFullRecordsByPortPromise: function (port, ip) {
        let pPort = 'p' + port;
        let promise;
        if ((ip !== null) && (ip !== undefined)) {
            promise = cSchema.censysModel.find({ 'ip': ip }).exists(pPort).exec();
        } else {
            promise = cSchema.censysModel.find({}).exists(pPort).exec();
        }
        return (promise);
    },
    getPortRecordsByPortPromise: function (port, ip) {
        let pPort = 'p' + port;
        let limitQuery = {};
        limitQuery['ip'] = 1;
        limitQuery[pPort] = 1;
        let promise;
        if ((ip !== null) && (ip !== undefined)) {
            promise = cSchema.censysModel.find({
                'ip': ip,
            }, limitQuery).exists(pPort).exec();
        } else {
            promise = cSchema.censysModel.find({}, limitQuery).exists(pPort).exec();
        }
        return (promise);
    },
    getIPListByPortPromise: function (port, limit, page) {
        let pPort = 'p' + port;
        if (limit !== undefined && limit > 0) {
            return cSchema.censysModel.find({}, { 'ip': 1 }).exists(pPort).skip(limit * (page - 1)).limit(limit).exec();
        }
        return cSchema.censysModel.find({}, { 'ip': 1 }).exists(pPort).exec();
    },
    getRecordsBySSLOrgPromise: function (org) {
        return cSchema.censysModel.find({
            'p443.https.tls.certificate.parsed.subject.organization': org,
        }).exec();
    },
    getSSLByCommonNamePromise: function (commonName) {
        return cSchema.censysModel.find({
            '$or': mongoSanitize.sanitize({ data: [{ 'p443.https.tls.certificate.parsed.subject.common_name': commonName },
            { 'p443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names': commonName }] }).data,
        }, { 'ip': 1, 'p443': 1 }).exec();
    },
    getSSLByZonePromise: function (zone, count) {
        let escZone = zone.replace('.', '\\.');
        let reZone = new RegExp('^.*\.' + escZone + '$');
        let promise;
        if (count) {
            promise = cSchema.censysModel.find({
                '$or': [{ 'p443.https.tls.certificate.parsed.subject.common_name': reZone },
                { 'p443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names': reZone },
                { 'p443.https.tls.certificate.parsed.subject.common_name': zone },
                { 'p443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names': zone }],
            }, { 'ip': 1, 'p443': 1 }).countDocuments().exec();
        } else {
            promise = cSchema.censysModel.find({
                '$or': mongoSanitize.sanitize({ data: [{ 'p443.https.tls.certificate.parsed.subject.common_name': reZone },
                { 'p443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names': reZone },
                { 'p443.https.tls.certificate.parsed.subject.common_name': zone },
                { 'p443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names': zone },
                ] }).data
            }, { 'ip': 1, 'p443': 1 }).exec();
        }
        return (promise);
    },
    getSSLByCorpNamePromise: function (internalDomain) {
        let reCorp = new RegExp('^.*\.' + internalDomain);
        return cSchema.censysModel.find({
            '$or': mongoSanitize.sanitize({ data: [{ 'p443.https.tls.certificate.parsed.subject.common_name': reCorp },
            { 'p443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names': reCorp }] }).data,
        }, { 'ip': 1, 'p443': 1 }).exec();
    },
    getSSLByValidity2kPromise: function () {
        let isBefore2010 = new RegExp('^200.*');
        return cSchema.censysModel.find({
            'p443.https.tls.certificate.parsed.validity.end': mongoSanitize.sanitize({ data: isBefore2010 }).data,
        }, { 'ip': 1, 'p443': 1 }).exec();
    },
    getSSLByValidityYearPromise: function (year) {
        let thisDecade = new RegExp('^' + year + '.*');
        return cSchema.censysModel.find({
            'p443.https.tls.certificate.parsed.validity.end': thisDecade,
        }, { 'ip': 1, 'p443': 1 }).exec();
    },
    getCorpSSLCountPromise: function (internalDomain) {
        let reCorp = new RegExp('^.*\.' + internalDomain);
        return cSchema.censysModel.find({
            '$or': mongoSanitize.sanitize({ data: [{ 'p443.https.tls.certificate.parsed.subject.common_name': reCorp },
            { 'p443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names': reCorp }] }).data,
        }).countDocuments().exec();
    },
    getSSLOrgCountPromise: function (org) {
        return cSchema.censysModel.find({
            'p443.https.tls.certificate.parsed.subject.organization': mongoSanitize.sanitize({ data: org }).data,
        }).countDocuments().exec();
    },
    getSSLProtocolCountPromise: function (protocol) {
        let promise;
        if (protocol !== 'tls') {
            let protocolTerm = 'p443.https.' + protocol + '.support';
            promise = cSchema.censysModel.find().where(protocolTerm).equals(true).countDocuments().exec();
        } else {
            promise = cSchema.censysModel.find({}).exists('p443.https.tls.version').countDocuments().exec();
        }
        return (promise);
    },
    getSSLAlgorithmPromise: function (algorithm, count) {
        let promise;
        if (count === true) {
            promise = cSchema.censysModel.find({
                'p443.https.tls.certificate.parsed.signature.signature_algorithm.name': mongoSanitize.sanitize({ data: algorithm }).data,
            }).countDocuments().exec();
        } else {
            promise = cSchema.censysModel.find({
                'p443.https.tls.certificate.parsed.signature.signature_algorithm.name': algorithm,
            }, {
                'ip': 1,
                'p443.https.tls.certificate': 1,
                'p443.https.tls.validation': 1
            }).exec();
        }
        return (promise);
    },
    getSSLAlgorithmByZonePromise: function (algorithm, zone, count) {
        let escZone = zone.replace('.', '\\.');
        let reZone = new RegExp('^.*\.' + escZone + '$');
        let promise;
        if (count === true) {
            promise = cSchema.censysModel.find({
                'p443.https.tls.certificate.parsed.signature.signature_algorithm.name': mongoSanitize.sanitize({ data: algorithm }).data,
                '$or': [{ 'p443.https.tls.certificate.parsed.subject.common_name': reZone },
                { 'p443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names': reZone }]
            }).countDocuments().exec();
        } else {
            promise = cSchema.censysModel.find({
                'p443.https.tls.certificate.parsed.signature.signature_algorithm.name': mongoSanitize.sanitize({ data: algorithm }).data,
                '$or': [{ 'p443.https.tls.certificate.parsed.subject.common_name': reZone },
                { 'p443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names': reZone }]
            },
                { 'ip': 1, 'p443.https.tls.certificate': 1, 'p443.https.tls.validation': 1 }).exec();
        }
        return (promise);
    },
    getSSLHeartbleedPromise: function (org, count) {
        let promise;
        let orgArray = [];
        if (org !== undefined && org !== null) {
            orgArray = org.split("|");
        }
        if (count) {
            promise = cSchema.censysModel.find({
                'p443': { '$exists': true },
                'p443.https.heartbleed.heartbleed_vulnerable': true,
                'p443.https.tls.certificate.parsed.subject.organization': { '$in': orgArray }
            }).countDocuments().exec();
        } else {
            if (org === undefined || org === null) {
                promise = cSchema.censysModel.find({
                    'p443': mongoSanitize.sanitize({ data: { '$exists': true } }).data,
                    'p443.https.heartbleed.heartbleed_vulnerable': true
                }).exec();
            } else {
                promise = cSchema.censysModel.find({
                    'p443': mongoSanitize.sanitize({ data: { '$exists': true } }).data,
                    'p443.https.heartbleed.heartbleed_vulnerable': true,
                    'p443.https.tls.certificate.parsed.subject.organization': { '$in': orgArray }
                }).exec();
            }
        }
        return (promise);
    },
    getFullCountPromise: function () {
        return cSchema.censysModel.countDocuments({}).exec();
    },
    getRecordsBySSLFingerprintPromise: function (fingerprint, count) {
        let promise;
        if (count) {
            promise = cSchema.censysModel.countDocuments({
                'p443.https.tls.certificate.parsed.fingerprint_sha1': fingerprint,
            }).exec();
        } else {
            promise = cSchema.censysModel.find({
                'p443.https.tls.certificate.parsed.fingerprint_sha1': fingerprint,
            }).exec();
        }
        return (promise);
    },
    getRecordsBySSL256FingerprintPromise: function (fingerprint, count) {
        let promise;
        if (count) {
            promise = cSchema.censysModel.countDocuments({
                'p443.https.tls.certificate.parsed.fingerprint_sha256': mongoSanitize.sanitize({ data: fingerprint }).data,
            }).exec();
        } else {
            promise = cSchema.censysModel.find({
                'p443.https.tls.certificate.parsed.fingerprint_sha256': mongoSanitize.sanitize({ data: fingerprint }).data,
            }).exec();
        }
        return (promise);
    },
    getRecordsBySSLSerialNumberPromise: function (serial_number, count) {
        if (serial_number.includes(":") == false) {
            serial_number = serial_number.replace(/..\B/g, '$&:');
        }

        let promise;

        if (count) {
            promise = cSchema.censysModel.countDocuments({
                'p443.https.tls.certificate.parsed.serial_number': mongoSanitize.sanitize({ data: serial_number }).data,
            }).exec();
        } else {
            promise = cSchema.censysModel.find({
                'p443.https.tls.certificate.parsed.serial_number': serial_number,
            }).exec();
        }
        return (promise);
    },
    getCAIssuersListPromise() {
        return cSchema.censysModel.distinct('p443.https.tls.chain.0.parsed.issuer.common_name').exec();
    },
    getRecordsBySSLCAPromise(caIssuer, count, limit, page) {
        let promise;
        if (count === true) {
            promise = cSchema.censysModel.countDocuments({
                'p443.https.tls.chain.0.parsed.issuer.common_name': mongoSanitize.sanitize({ data: caIssuer }).data,
            }).exec();
        } else {
            if (limit > 0) {
                promise = cSchema.censysModel.find({
                    'p443.https.tls.chain.0.parsed.issuer.common_name': mongoSanitize.sanitize({ data: caIssuer }).data,
                }).skip(limit * (page - 1)).limit(limit).exec();
            } else {
                promise = cSchema.censysModel.find({
                    'p443.https.tls.chain.0.parsed.issuer.common_name': mongoSanitize.sanitize({ data: caIssuer }).data,
                }).exec();
            }
        }
        return (promise);
    },
    getHttpHeaderPromise: function (header, zone, count) {
        let headerQuery = 'p80.http.get.headers.' + header;
        let query = {};
        if (zone != null && zone !== '') {
            query = { 'zones': zone };
        }
        let promise;
        if (count === true) {
            promise = cSchema.censysModel.find(query).exists(headerQuery).countDocuments().exec();
        } else {
            promise = cSchema.censysModel.find(query).exists(headerQuery).select(headerQuery + ' zones' + ' ip').exec();
        }
        return (promise);
    },
    getUnknownHttpHeaderPromise: function (header, zone, count) {
        let query = { 'p80.http.get.headers.unknown.key': header };
        if (zone != null && zone !== '') {
            query['zones'] = zone;
        }
        let promise;
        if (count === true) {
            promise = cSchema.censysModel.countDocuments(query).exec();
        } else {
            promise = cSchema.censysModel.find(query).select('p80.http.get.headers.unknown ' + ' zones' + ' ip').exec();
        }
        return (promise);
    },
    getHttpHeaderByValuePromise: function (header, value, zone) {
        let headerQuery = 'p80.http.get.headers.' + header;
        let query = { [headerQuery]: mongoSanitize.sanitize({ data: value }).data };
        if (zone != null && zone !== '') {
            query['zones'] = zone;
        }
        return cSchema.censysModel.find(query).select(headerQuery + ' zones' + ' ip').exec();
    },
    getUnknownHttpHeaderByValuePromise: function (header, value, zone) {
        let query = { 'p80.http.get.headers.unknown.key': header, 'p80.http.get.headers.unknown.value': value };
        if (zone != null && zone !== '') {
            query['zones'] = zone;
        }
        return cSchema.censysModel.find(query).select('p80.http.get.headers.unknown ' + ' zones' + ' ip').exec();
    },
    getDistinctHttpHeaderPromise: function (header, zone) {
        let headerQuery = 'p80.http.get.headers.' + header;
        let query;
        if (zone == null || zone === '') {
            query = { '$match': { [headerQuery]: { '$exists': true } } };
        } else {
            query = { '$match': { [headerQuery]: { '$exists': true }, 'zones': zone } };
        }
        return cSchema.censysModel.aggregate([query, { '$group': { '_id': '$' + headerQuery, 'count': { '$sum': 1 } } }]).sort({ 'count': 'descending' }).exec();
    },
    getDistinctUnknownHttpHeaderPromise: function (header, zone) {
        let query = {}
        if (zone == null || zone === '') {
            query = { 'p80.http.get.headers.unknown.key': header };
        } else {
            query = { 'p80.http.get.headers.unknown.key': header, 'zones': zone };
        }
        return cSchema.censysModel.aggregate([{ "$match": query },
        {
            "$project": {
                "headers": {
                    "$filter": {
                        "input": '$p80.http.get.headers.unknown',
                        "as": "header",
                        "cond": { "$eq": ["$$header.key", header] }
                    }
                }
            }
        },
        { '$group': { "_id": "$headers.value", "count": { "$sum": 1 } } }, { "$project": { "_id": { "$arrayElemAt": ["$_id", 0] }, "count": "$count" } }])
    },
};
