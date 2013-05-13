/*
 * Copyright (C) 2013 Jolla Ltd. <chris.adams@jollamobile.com>
 *
 * You may use this file under the terms of the BSD license as follows:
 *
 * "Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Nemo Mobile nor the names of its contributors
 *     may be used to endorse or promote products derived from this
 *     software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
 */

#ifndef TWITTERINTERFACE_H
#define TWITTERINTERFACE_H

#include "socialnetworkinterface.h"

#include <QtCore/QStringList>
#include <QtCore/QString>

class QNetworkReply;

class TwitterTweetInterface;
class TwitterPlaceInterface;
class TwitterUserInterface;
class IdentifiableContentItemInterface;

/*
 * NOTE: if you construct one of these in C++ directly,
 * you MUST call classBegin() and componentCompleted()
 * directly after construction.
 */

class CacheEntry;
class TwitterInterfacePrivate;
class TwitterInterface : public SocialNetworkInterface
{
    Q_OBJECT

    Q_PROPERTY(QString oauthToken READ oauthToken WRITE setOAuthToken NOTIFY oauthTokenChanged)
    Q_PROPERTY(QString oauthTokenSecret READ oauthTokenSecret WRITE setOAuthTokenSecret NOTIFY oauthTokenSecretChanged)
    Q_PROPERTY(QString consumerKey READ consumerKey WRITE setConsumerKey NOTIFY consumerKeyChanged)
    Q_PROPERTY(QString consumerSecret READ consumerSecret WRITE setConsumerSecret NOTIFY consumerSecretChanged)

    Q_ENUMS(ContentItemType)

public:
    enum ContentItemType {
        NotInitialized = 0,
        Unknown = 1,
        User,
        Place,
        Tweet
    };

public:
    explicit TwitterInterface(QObject *parent = 0);

    // properties
    QString oauthToken() const;
    void setOAuthToken(const QString &token);
    QString oauthTokenSecret() const;
    void setOAuthTokenSecret(const QString &tokenSecret);
    QString consumerKey() const;
    void setConsumerKey(const QString &key);
    QString consumerSecret() const;
    void setConsumerSecret(const QString &secret);

Q_SIGNALS:
    void oauthTokenChanged();
    void oauthTokenSecretChanged();
    void consumerKeyChanged();
    void consumerSecretChanged();

    // SocialNetworkInterface
public:
    void componentComplete();
    Q_INVOKABLE void populate();
protected:
    QNetworkReply *getRequest(const QString &objectIdentifier, const QString &extraPath, const QStringList &whichFields, const QVariantMap &extraData);
    QNetworkReply *postRequest(const QString &objectIdentifier, const QString &extraPath, const QVariantMap &data, const QVariantMap &extraData);
    QNetworkReply *deleteRequest(const QString &objectIdentifier, const QString &extraPath, const QVariantMap &extraData);
    QString dataSection(int type, const QVariantMap &data) const;
    void updateInternalData(QList<CacheEntry*> data);
    void populateDataForNode(IdentifiableContentItemInterface *currentNode);
    void populateDataForNode(const QString &unseenNodeIdentifier);
    ContentItemInterface *contentItemFromData(QObject *parent, const QVariantMap &data) const;

    // private API for all Twitter adapters to use
private:
    QString currentUserIdentifier() const;
    QVariantMap twitterContentItemData(ContentItemInterface *contentItem);
    void setTwitterContentItemData(ContentItemInterface *contentItem, const QVariantMap &data);
    friend class TwitterPlaceInterfacePrivate;
    friend class TwitterTweetInterfacePrivate;
    friend class TwitterUserInterfacePrivate;

    // impl. detail
private:
    void retrieveRelatedContent(IdentifiableContentItemInterface *whichNode);
    void continuePopulateDataForUnseenNode(const QVariantMap &nodeData);
    void continuePopulateDataForSeenNode(const QVariantMap &nodeData, const QUrl &requestUrl);

    // private data.
private:
    Q_DECLARE_PRIVATE(TwitterInterface)
    Q_PRIVATE_SLOT(d_func(), void finishedHandler())
    Q_PRIVATE_SLOT(d_func(), void errorHandler(QNetworkReply::NetworkError))
    Q_PRIVATE_SLOT(d_func(), void sslErrorsHandler(const QList<QSslError>&))
};

#endif // TWITTERINTERFACE_H
