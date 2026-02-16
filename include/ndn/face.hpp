/**
 * @file face.hpp
 * @brief NDN Face interface
 *
 * A Face abstracts the connection to a physical network.
 * Concrete implementation classes for different transports such as
 * ESP-NOW, BLE, and Wi-Fi inherit from this interface.
 *
 * @see https://docs.named-data.net/NDN-packet-spec/current/
 */

#pragma once

#include "ndn/common.hpp"
#include <functional>

namespace ndn {

/**
 * @brief Packet receive callback
 *
 * Callback function type invoked when a Face receives a packet.
 *
 * @param faceId ID of the Face that received the packet
 * @param data Pointer to the received packet data
 * @param len Packet size in bytes
 */
using PacketCallback = std::function<void(FaceId faceId, const uint8_t* data, size_t len)>;

/**
 * @brief NDN Face abstract base class
 *
 * A Face abstracts a network interface.
 * Each transport (ESP-NOW, BLE, etc.) inherits from this class.
 *
 * @code
 * // Example using ESP-NOW Face
 * EspNowFace face;
 * face.setPacketCallback([](FaceId id, const uint8_t* data, size_t len) {
 *     // Handle received packet
 * });
 * face.start();
 *
 * // Send a packet
 * face.broadcast(packetData, packetLen);
 * @endcode
 */
class Face {
public:
    /**
     * @brief Destructor
     */
    virtual ~Face() = default;

    /**
     * @brief Get the Face ID
     * @return FaceId identifying this Face
     */
    virtual FaceId id() const = 0;

    /** @name Lifecycle management
     * @{
     */

    /**
     * @brief Start the Face
     *
     * Initializes the transport and begins sending/receiving packets.
     *
     * @return Error::Success on success, error code on failure
     */
    virtual Error start() = 0;

    /**
     * @brief Stop the Face
     *
     * Stops sending/receiving packets and releases resources.
     */
    virtual void stop() = 0;
    /** @} */

    /** @name Packet transmission
     * @{
     */

    /**
     * @brief Send a packet
     *
     * Sends a packet to the default destination.
     *
     * @param data Packet data to send
     * @param len Packet size in bytes
     * @return Error::Success on success, Error::SendFailed on failure
     */
    virtual Error send(const uint8_t* data, size_t len) = 0;

    /**
     * @brief Send a packet to a specific Face
     *
     * @param destFace Destination Face ID
     * @param data Packet data to send
     * @param len Packet size in bytes
     * @return Error::Success on success, Error::SendFailed on failure
     */
    virtual Error sendTo(FaceId destFace, const uint8_t* data, size_t len) = 0;

    /**
     * @brief Broadcast a packet to all nodes
     *
     * @param data Packet data to send
     * @param len Packet size in bytes
     * @return Error::Success on success, Error::SendFailed on failure
     */
    virtual Error broadcast(const uint8_t* data, size_t len) = 0;
    /** @} */

    /**
     * @brief Get the maximum payload size
     *
     * Returns the maximum number of bytes this Face can send at once.
     * ESP-NOW v1: 250 bytes, v2: up to 1470 bytes.
     *
     * @return Maximum payload size (bytes)
     */
    virtual size_t maxPayloadSize() const = 0;

    /**
     * @brief Set the packet receive callback
     *
     * @param callback Callback function invoked on packet reception
     */
    void setPacketCallback(PacketCallback callback) { packetCallback_ = callback; }

protected:
    /**
     * @brief Internal handler for packet reception
     *
     * Derived classes call this method when a packet is received.
     *
     * @param faceId ID of the Face that received the packet
     * @param data Received packet data
     * @param len Packet size in bytes
     */
    void onPacketReceived(FaceId faceId, const uint8_t* data, size_t len) {
        if (packetCallback_) {
            packetCallback_(faceId, data, len);
        }
    }

    PacketCallback packetCallback_;  ///< Packet receive callback
};

}  // namespace ndn
